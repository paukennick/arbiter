module Jobs
  class ImageResolver
    def initialize
      @root = ENV["IMAGE_ROOT"]
    end

    def resolve(path)
      full = File.expand_path(path)
      if @root # expect: arbiter/ruby.path-confinement-optional
        raise ArgumentError, "outside root" unless full.start_with?(@root + File::SEPARATOR)
      end
      full
    end
  end
end
