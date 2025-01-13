import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import { authMiddleware } from "../../middleware";
import ServiceModel from "../../model/ServiceModel";

// Create a new instance of the Express Router
const ServiceRouter = Router();

// @route    Get api/services/
// @desc     Get all services
// @access   Private
ServiceRouter.get(
  '/',
  authMiddleware,
  async (req: Request, res: Response) => {
    try {
      const services = await ServiceModel.find();
      return res.json({ services: services });
    } catch (err) {
      console.log('error finding services ===> ', err);
      return res.status(500).send({ err })
    }
  }
)

// @route    Post api/services/create
// @desc     Post all services
// @access   Private
ServiceRouter.post(
  '/create',
  authMiddleware,
  check("serviceName", "ServiceName is required").exists(),
  check("tierName", "TierName is required").exists(),
  check("description", "Description is required").exists(),
  check("connectionURL", "ConnectionURL is required").exists(),
  check("dailyPrice", "DailyPrice is required").exists(),
  check("weeklyPrice", "WeeklyPrice is required").exists(),
  check("monthlyPrice", "MonthlyPrice is required").exists(),
  async (req: Request, res: Response) => {
    try {
      const service = new ServiceModel({
        serviceName: req.body.serviceName,
        tierName: req.body.tierName,
        description: req.body.description,
        connectionURL: req.body.connectionURL,
        dailyPrice: req.body.dailyPrice,
        weeklyPrice: req.body.weeklyPrice,
        monthlyPrice: req.body.monthlyPrice,
      });

      await service.save();
      return res.json({ success: true });
    } catch (err) {
      console.log('error finding services ===> ', err);
      return res.status(500).send({ err })
    }
  }
)

export default ServiceRouter;