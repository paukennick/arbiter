module Jobs
  class ImageResolver
    ROOT = File.expand_path(ENV.fetch("IMAGE_ROOT", "/srv/images"))

    def resolve(path)
      full = File.expand_path(path, ROOT)
      raise ArgumentError, "outside root" unless full.start_with?(ROOT + File::SEPARATOR)
      full
    end
  end
end
